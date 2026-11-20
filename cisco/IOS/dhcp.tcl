#==============================================================================
# dhcp_verify.tcl  -  CIS-style DHCP hardening verification (classic Cisco IOS)
#
# READ-ONLY. Executes "show" commands only. Never enters configuration mode,
# never applies or suggests-by-execution any remediation.
#
# Usage  : Switch# tclsh flash:dhcp_verify.tcl
# Target : classic IOS native Tcl interpreter (written for the Tcl 8.3.x subset:
#          no lassign/dict/lsearch -all/-inline/eq/ne/string repeat/{*}).
#
# Adding a module: write ::dv::ctl_xxx (use ::dv::add / ::dv::ev) and register
# it with ::dv::register at the bottom of this file.
#==============================================================================

catch {namespace delete ::dv}

namespace eval ::dv {
    variable VERSION "1.0.0"

    # ---- tunables (edit here, nothing else needs to change) ----------------
    variable CFG
    array set CFG {
        max_rate        15
        skip_shutdown   0
        relay_not_fail  1
        use_color       1
    }

    variable TITLE    "Cisco IOS DHCP Hardening Verification"
    variable LINKEDIN "LinkedIn : alisedighnezhad"

    variable CONTROLS {}
    variable FINDINGS {}
    variable COUNT
    array set COUNT {PASS 0 FAIL 0 WARNING 0 HINT 0 N/A 0 ERROR 0}

    variable RAW
    array set RAW {}
    variable RUNOK 0
    variable RUNERR ""
    variable SWOK 0
    variable HOSTNAME "unknown"

    # parsed running-config
    variable G {}
    variable IFL
    array set IFL {}
    variable IFORDER {}

    # parsed "show interfaces switchport"
    variable PORT
    array set PORT {}
    variable PORTS {}

    # parsed "show ip dhcp snooping"
    variable SN
    array set SN {global "" opt82 "" opt82_untrusted "" cfgvlans "" opvlans "" opseen 0}
}

#------------------------------------------------------------------------------
# Generic helpers
#------------------------------------------------------------------------------
proc ::dv::rep {ch n} {
    set s ""
    for {set i 0} {$i < $n} {incr i} {append s $ch}
    return $s
}

# ANSI colour helper. Set CFG(use_color) 0 if your terminal prints raw escape codes.
proc ::dv::clr {style text} {
    variable CFG
    if {!$CFG(use_color)} {return $text}
    switch -exact -- $style {
        PASS    {set code "1;32"}
        FAIL    {set code "1;31"}
        WARNING {set code "1;33"}
        HINT    {set code "1;36"}
        ERROR   {set code "1;35"}
        N/A     {set code "37"}
        TITLE   {set code "1;96"}
        LINK    {set code "94"}
        BOLD    {set code "1"}
        DIM     {set code "90"}
        default {return $text}
    }
    set esc [format %c 27]
    return "${esc}\[${code}m${text}${esc}\[0m"
}

proc ::dv::rank {s} {
    switch -exact -- $s {
        N/A     {return 0}
        PASS    {return 1}
        HINT    {return 2}
        WARNING {return 3}
        ERROR   {return 4}
        FAIL    {return 5}
    }
    return 4
}

# add a status finding / an evidence line to the control being evaluated
proc ::dv::add {status text {items {}}} {
    variable FINDINGS
    lappend FINDINGS [list $status $text $items]
}
proc ::dv::ev {text {items {}}} {
    variable FINDINGS
    lappend FINDINGS [list EVIDENCE $text $items]
}

proc ::dv::register {id title procname} {
    variable CONTROLS
    lappend CONTROLS [list $id $title $procname]
}

# Run one IOS show command. Returns {ok text}; ok=0 on Tcl error or IOS "%" error.
proc ::dv::exec_show {cmd} {
    if {[catch {exec $cmd} out]} {
        return [list 0 $out]
    }
    set out [string map [list "\r" ""] $out]
    if {[regexp -nocase -line {^% *(invalid input|incomplete command|ambiguous command|unrecognized command|access denied)} $out]} {
        return [list 0 $out]
    }
    return [list 1 $out]
}

# Lazily fetched "show running-config all" (used only to resolve default state)
proc ::dv::get_all {} {
    variable RAW
    if {![info exists RAW(all,ok)]} {
        set r [exec_show "show running-config all"]
        set RAW(all,ok)   [lindex $r 0]
        set RAW(all,text) [lindex $r 1]
    }
    return $RAW(all,ok)
}
proc ::dv::all_has {rx} {
    variable RAW
    return [regexp -line $rx $RAW(all,text)]
}

# Normalise abbreviated interface names (Gi1/0/1 -> GigabitEthernet1/0/1)
proc ::dv::canon {name} {
    set name [string trim $name]
    if {![regexp {^([A-Za-z][A-Za-z-]*)([0-9][0-9/.:]*)$} $name _m pfx num]} {
        return $name
    }
    set l [string tolower $pfx]
    if {[string length $l] < 2} {return $name}
    foreach full {GigabitEthernet FastEthernet TenGigabitEthernet TwentyFiveGigE
                  FortyGigabitEthernet HundredGigE Port-channel Ethernet Vlan Loopback} {
        if {[string first $l [string tolower $full]] == 0} {
            return "${full}${num}"
        }
    }
    return $name
}

# VLAN list helpers ("10,20,30-40" <-> array / compact string)
proc ::dv::vlan_expand {spec arrname} {
    upvar $arrname arr
    foreach tok [split [string map [list "," " "] $spec] " "] {
        if {[string length $tok] == 0} continue
        if {[regexp {^([0-9]+)-([0-9]+)$} $tok _m a b]} {
            scan $a %d a
            scan $b %d b
            if {$b > 4094} {set b 4094}
            for {set i $a} {$i <= $b} {incr i} {set arr($i) 1}
        } elseif {[regexp {^[0-9]+$} $tok]} {
            scan $tok %d v
            set arr($v) 1
        }
    }
}

proc ::dv::vlan_compress {lst} {
    set lst [lsort -integer $lst]
    set out {}
    set start ""
    set prev ""
    foreach v $lst {
        if {[string length $start] == 0} {
            set start $v
            set prev $v
            continue
        }
        if {$v == $prev + 1} {
            set prev $v
            continue
        }
        if {$start == $prev} {lappend out $start} else {lappend out "$start-$prev"}
        set start $v
        set prev $v
    }
    if {[string length $start] > 0} {
        if {$start == $prev} {lappend out $start} else {lappend out "$start-$prev"}
    }
    return [join $out ","]
}

#------------------------------------------------------------------------------
# running-config access
#------------------------------------------------------------------------------
proc ::dv::g_all {rx} {
    variable G
    set out {}
    foreach l $G {
        if {[regexp $rx $l]} {lappend out $l}
    }
    return $out
}
proc ::dv::g_find {rx} {
    return [lindex [g_all $rx] 0]
}
proc ::dv::if_has {ifc line} {
    variable IFL
    if {![info exists IFL($ifc)]} {return 0}
    return [expr {[lsearch -exact $IFL($ifc) $line] >= 0}]
}
# first capture group of the first matching interface sub-command, or ""
proc ::dv::if_cap {ifc rx} {
    variable IFL
    if {![info exists IFL($ifc)]} {return ""}
    foreach l $IFL($ifc) {
        if {[regexp $rx $l _m c]} {return $c}
    }
    return ""
}

proc ::dv::parse_run {text} {
    variable G
    variable IFL
    variable IFORDER
    variable HOSTNAME
    set G {}
    set IFORDER {}
    set cur ""
    foreach line [split $text "\n"] {
        set line [string trimright $line]
        if {[string length $line] == 0} continue
        if {[string match "!*" $line]} {
            set cur ""
            continue
        }
        if {[string match " *" $line]} {
            if {[string length $cur] > 0} {
                lappend IFL($cur) [string trim $line]
            }
            continue
        }
        set cur ""
        if {[regexp {^interface (\S+)} $line _m nm]} {
            set cur [canon $nm]
            if {![info exists IFL($cur)]} {
                set IFL($cur) {}
                lappend IFORDER $cur
            }
            continue
        }
        lappend G $line
        if {[regexp {^hostname (\S+)} $line _m hn]} {set HOSTNAME $hn}
    }
}

#------------------------------------------------------------------------------
# "show interfaces switchport" parsing -> PORT(<canon>,field)
#------------------------------------------------------------------------------
proc ::dv::parse_switchport {text} {
    variable PORT
    variable PORTS
    set cur ""
    foreach line [split $text "\n"] {
        set line [string trim $line]
        if {[regexp {^Name:\s*(\S+)} $line _m nm]} {
            set cur [canon $nm]
            if {![info exists PORT($cur,admin)]} {lappend PORTS $cur}
            set PORT($cur,sw)    ""
            set PORT($cur,admin) ""
            set PORT($cur,oper)  ""
            set PORT($cur,avlan) ""
            set PORT($cur,vvlan) ""
            set PORT($cur,src)   "show"
            continue
        }
        if {[string length $cur] == 0} continue
        if {[regexp {^Switchport:\s*(\S+)} $line _m v]} {
            set PORT($cur,sw) [string tolower $v]
        } elseif {[regexp {^Administrative Mode:\s*(.+)$} $line _m v]} {
            set PORT($cur,admin) [string tolower [string trim $v]]
        } elseif {[regexp {^Operational Mode:\s*(.+)$} $line _m v]} {
            set PORT($cur,oper) [string tolower [string trim $v]]
        } elseif {[regexp {^Access Mode VLAN:\s*([0-9]+)} $line _m v]} {
            set PORT($cur,avlan) $v
        } elseif {[regexp {^Voice VLAN:\s*([0-9]+)} $line _m v]} {
            set PORT($cur,vvlan) $v
        }
    }
}

# Fallback/complement: ports with "switchport mode access" in running-config
proc ::dv::merge_run_ports {} {
    variable IFORDER
    variable PORT
    variable PORTS
    foreach i $IFORDER {
        if {[info exists PORT($i,admin)]} continue
        if {![if_has $i "switchport mode access"]} continue
        set PORT($i,sw)    "enabled"
        set PORT($i,admin) "static access"
        set PORT($i,oper)  ""
        set v [if_cap $i {^switchport access vlan ([0-9]+)$}]
        if {[string length $v] == 0} {set v 1}
        set PORT($i,avlan) $v
        set PORT($i,vvlan) [if_cap $i {^switchport voice vlan ([0-9]+)$}]
        set PORT($i,src)   "run"
        lappend PORTS $i
    }
}

# 0 = not access, 1 = administratively access, 2 = dynamic admin mode but operationally access
proc ::dv::is_access {p} {
    variable PORT
    if {![info exists PORT($p,admin)]} {return 0}
    set a $PORT($p,admin)
    set o $PORT($p,oper)
    if {[string match "static access*" $a]} {return 1}
    if {[string match "dynamic*" $a] && [string match "static access*" $o]} {return 2}
    return 0
}

proc ::dv::access_ports {} {
    variable PORTS
    variable CFG
    set out {}
    foreach p $PORTS {
        if {[is_access $p] == 0} continue
        if {$CFG(skip_shutdown) && [if_has $p "shutdown"]} continue
        lappend out $p
    }
    return $out
}

proc ::dv::swp_note {} {
    add ERROR "Access-port classification is incomplete: \"show interfaces switchport\" was unavailable; only ports with \"switchport mode access\" in running-config were considered."
}

#------------------------------------------------------------------------------
# "show ip dhcp snooping" parsing -> SN()
#------------------------------------------------------------------------------
proc ::dv::parse_snoop {text} {
    variable SN
    set mode ""
    foreach line [split $text "\n"] {
        set line [string trim $line]
        if {[regexp -nocase {DHCP snooping is (enabled|disabled)\s*$} $line _m st]} {
            set SN(global) [string tolower $st]
            set mode ""
            continue
        }
        if {[regexp -nocase {configured on (the )?following VLANs} $line]} {
            set mode cfg
            continue
        }
        if {[regexp -nocase {operational on (the )?following VLANs} $line]} {
            set mode op
            set SN(opseen) 1
            continue
        }
        if {[regexp -nocase {Insertion of option 82 is (enabled|disabled)} $line _m st]} {
            set SN(opt82) [string tolower $st]
            set mode ""
            continue
        }
        if {[regexp -nocase {Option 82 on untrusted port is (not )?allowed} $line _m neg]} {
            if {[string length $neg] > 0} {set SN(opt82_untrusted) "not allowed"} else {set SN(opt82_untrusted) "allowed"}
            set mode ""
            continue
        }
        if {[string length $mode] > 0} {
            if {[regexp {^[0-9][0-9, -]*$} $line]} {
                if {$mode == "cfg"} {append SN(cfgvlans) ",$line"} else {append SN(opvlans) ",$line"}
                continue
            }
            set mode ""
        }
    }
}

#------------------------------------------------------------------------------
# Evidence collection (all read-only show commands)
#------------------------------------------------------------------------------
proc ::dv::collect {} {
    variable RAW
    variable RUNOK
    variable RUNERR
    variable SWOK
    foreach {name cmd} {
        run    "show running-config"
        snoop  "show ip dhcp snooping"
        db     "show ip dhcp snooping database"
        swp    "show interfaces switchport"
    } {
        set r [exec_show $cmd]
        set RAW($name,ok)   [lindex $r 0]
        set RAW($name,text) [lindex $r 1]
    }
    if {$RAW(run,ok)} {
        set RUNOK 1
        parse_run $RAW(run,text)
    } else {
        set RUNOK 0
        set RUNERR [lindex [split [string trim $RAW(run,text)] "\n"] 0]
    }
    if {$RAW(snoop,ok)} {parse_snoop $RAW(snoop,text)}
    if {$RAW(swp,ok)} {
        set SWOK 1
        parse_switchport $RAW(swp,text)
    }
    if {$RUNOK} {merge_run_ports}
}

#------------------------------------------------------------------------------
# DHCP-01 : DHCP service
#------------------------------------------------------------------------------
proc ::dv::dhcp_bindings {} {
    set r [exec_show "show ip dhcp binding"]
    if {![lindex $r 0]} {return -1}
    set n 0
    foreach l [split [lindex $r 1] "\n"] {
        if {[regexp {^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s} [string trim $l]]} {incr n}
    }
    return $n
}

proc ::dv::ctl_dhcp01 {} {
    variable IFORDER
    variable CFG
    set pools {}
    foreach l [g_all {^ip dhcp pool \S+}] {
        if {[regexp {^ip dhcp pool (\S+)} $l _m nm]} {lappend pools $nm}
    }
    set relay {}
    foreach i $IFORDER {
        if {[string length [if_cap $i {^(ip helper-address) }]] > 0} {lappend relay $i}
    }

    set state ""
    set basis ""
    if {[string length [g_find {^no service dhcp$}]] > 0} {
        set state disabled
        set basis "no service dhcp (explicit)"
    } elseif {[string length [g_find {^service dhcp$}]] > 0} {
        set state enabled
        set basis "service dhcp (explicit)"
    } elseif {[get_all]} {
        if {[all_has {^no service dhcp\s*$}]} {
            set state disabled
            set basis "no service dhcp (effective default, from show running-config all)"
        } elseif {[all_has {^service dhcp\s*$}]} {
            set state enabled
            set basis "service dhcp (effective default, from show running-config all)"
        }
    }

    if {[llength $pools] > 0} {
        if {$state == "disabled"} {
            add HINT "DHCP Server is configured ([llength $pools] pool(s)) but the DHCP service is disabled, so the server is currently inactive."
        } elseif {$state == "enabled"} {
            add HINT "DHCP Server is configured and active ([llength $pools] pool(s), service dhcp enabled)."
        } else {
            add HINT "DHCP Server is configured ([llength $pools] pool(s)); service state could not be confirmed."
        }
        add HINT "Recommendation: migrate DHCP Server functionality to a dedicated DHCP Server. (Service was NOT modified.)"
        ev "DHCP pools" $pools
    } else {
        set nb -1
        if {$state != "disabled"} {set nb [dhcp_bindings]}
        if {$nb > 0} {
            add HINT "DHCP Server appears active: $nb server binding(s) present although no pool is visible in running-config."
            add HINT "Recommendation: migrate DHCP Server functionality to a dedicated DHCP Server. (Service was NOT modified.)"
        } elseif {$state == "disabled"} {
            add PASS "No DHCP Server configured and the DHCP service is disabled."
        } elseif {$state == "enabled"} {
            if {[llength $relay] > 0 && $CFG(relay_not_fail)} {
                add WARNING "No DHCP Server configured and service dhcp is enabled, but DHCP relay (ip helper-address) is in use on [llength $relay] interface(s). 'no service dhcp' would also disable the relay agent, so this is not reported as FAIL."
            } else {
                add FAIL "No DHCP Server configured but the DHCP service is still enabled."
            }
        } else {
            add ERROR "Cannot determine whether \"service dhcp\" is enabled: no explicit line in running-config and \"show running-config all\" did not resolve it."
        }
    }
    if {[string length $basis] > 0} {ev "Service state: $basis"}
    if {[llength $relay] > 0} {
        ev "DHCP relay (ip helper-address) found on [llength $relay] interface(s); relay is NOT treated as a DHCP Server. Note: 'no service dhcp' also disables the IOS relay agent - verify before remediating." $relay
    }
}

#------------------------------------------------------------------------------
# DHCP-02 : DHCP Snooping (global + VLAN)
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp02 {} {
    variable SN
    variable SWOK
    variable PORT
    set globalOn [expr {[string length [g_find {^ip dhcp snooping$}]] > 0}]
    if {$globalOn} {
        if {$SN(global) == "disabled"} {
            add ERROR "Inconsistent evidence: running-config contains \"ip dhcp snooping\" but \"show ip dhcp snooping\" reports snooping disabled."
        } elseif {$SN(global) == "enabled"} {
            add PASS "DHCP Snooping is enabled globally (running-config and operational state agree)."
        } else {
            add ERROR "\"ip dhcp snooping\" is present in running-config but the operational state could not be confirmed (\"show ip dhcp snooping\" unavailable or unparsable)."
        }
        ev "running-config: ip dhcp snooping"
    } else {
        add FAIL "DHCP Snooping is not enabled globally (\"ip dhcp snooping\" not found in running-config)."
    }
    if {[string length $SN(global)] > 0} {ev "show ip dhcp snooping: snooping $SN(global)"}

    array set cfgv {}
    foreach l [g_all {^ip dhcp snooping vlan [0-9][0-9, -]*$}] {
        if {[regexp {^ip dhcp snooping vlan (.*)$} $l _m spec]} {vlan_expand $spec cfgv}
    }
    if {[array size cfgv] == 0} {
        add FAIL "DHCP Snooping is not enabled on any VLAN (no \"ip dhcp snooping vlan ...\" line in running-config)."
        return
    }
    ev "DHCP Snooping VLANs (configured): [vlan_compress [array names cfgv]]"

    if {!$SWOK} {swp_note}
    array set rel {}
    foreach p [access_ports] {
        if {[string length $PORT($p,avlan)] > 0} {set rel($PORT($p,avlan)) 1}
        if {[string length $PORT($p,vvlan)] > 0} {set rel($PORT($p,vvlan)) 1}
    }
    if {[array size rel] == 0} {
        if {$SWOK} {ev "No access ports found; per-VLAN coverage check not applicable."}
        return
    }
    set miss {}
    foreach v [array names rel] {
        if {![info exists cfgv($v)]} {lappend miss $v}
    }
    if {[llength $miss] > 0} {
        add FAIL "DHCP Snooping is not enabled on VLAN(s) used by access/voice ports: [vlan_compress $miss]"
    } else {
        add PASS "DHCP Snooping is enabled on all VLANs used by access/voice ports ([vlan_compress [array names rel]])."
    }
    if {$SN(opseen)} {
        array set opv {}
        vlan_expand $SN(opvlans) opv
        set notop {}
        foreach v [array names rel] {
            if {[info exists cfgv($v)] && ![info exists opv($v)]} {lappend notop $v}
        }
        if {[llength $notop] > 0} {
            add WARNING "VLAN(s) configured for snooping but not operational (VLAN missing/inactive?): [vlan_compress $notop]"
        }
    }
}

#------------------------------------------------------------------------------
# DHCP-03 : trusted interfaces
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp03 {} {
    variable IFORDER
    variable SWOK
    set trusted {}
    foreach i $IFORDER {
        if {[if_has $i "ip dhcp snooping trust"]} {lappend trusted $i}
    }
    set n [llength $trusted]
    if {$n == 0} {
        if {[string length [g_find {^ip dhcp snooping$}]] > 0} {
            add WARNING "No trusted interface configured while snooping is enabled; legitimate DHCP server replies arriving from the network would be dropped."
        } else {
            add N/A "No trusted interfaces and DHCP Snooping is not enabled globally (see DHCP-02)."
        }
        return
    }
    ev "Trusted interfaces found: $n" $trusted
    if {$n > 1} {
        add WARNING "More than one Trusted interface detected ($n)." $trusted
    }
    set acc {}
    foreach i $trusted {
        if {[is_access $i] > 0} {lappend acc $i}
    }
    if {[llength $acc] > 0} {
        add WARNING "Trusted interface configured as an Access Port (a DHCP server behind it would be trusted)." $acc
    }
    if {!$SWOK} {swp_note}
    if {$n == 1 && [llength $acc] == 0 && $SWOK} {
        add PASS "Single Trusted interface, not an Access Port." $trusted
    }
}

#------------------------------------------------------------------------------
# DHCP-04 : rate limiting on access ports
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp04 {} {
    variable CFG
    variable SWOK
    set max $CFG(max_rate)
    set ports [access_ports]
    if {!$SWOK} {swp_note}
    if {[llength $ports] == 0} {
        if {$SWOK} {add N/A "No applicable access ports found."}
        return
    }
    set missing {}
    set high {}
    set bad {}
    set skipped {}
    set dyn {}
    set okc 0
    foreach p $ports {
        if {[is_access $p] == 2} {lappend dyn $p}
        if {[if_has $p "ip dhcp snooping trust"]} {
            lappend skipped $p
            continue
        }
        set r [if_cap $p {^ip dhcp snooping limit rate ([0-9]+)}]
        if {[string length $r] == 0} {
            lappend missing $p
            continue
        }
        scan $r %d rn
        if {$rn < 1} {
            lappend bad "$p  configured rate: $rn (expected 1-$max)"
        } elseif {$rn <= $max} {
            incr okc
        } else {
            lappend high "$p  configured rate: $rn (expected maximum: $max)"
        }
    }
    if {[llength $missing] > 0} {
        add FAIL "No DHCP Snooping rate limit configured on [llength $missing] access port(s)." $missing
    }
    if {[llength $high] > 0} {
        add WARNING "Rate limit above the expected maximum on [llength $high] access port(s)." $high
    }
    if {[llength $bad] > 0} {
        add WARNING "Unexpected rate limit value on [llength $bad] access port(s)." $bad
    }
    if {$okc > 0} {
        add PASS "$okc access port(s) have a rate limit within 1-$max pps."
    }
    if {$okc == 0 && [llength $missing] == 0 && [llength $high] == 0 && [llength $bad] == 0} {
        add N/A "All access ports are trusted; rate limit check not applicable."
    }
    ev "Evaluated [expr {[llength $ports] - [llength $skipped]}] untrusted access port(s) of [llength $ports] total"
    if {[llength $skipped] > 0} {
        ev "Trusted access ports excluded from the rate-limit check (see DHCP-03)" $skipped
    }
    if {[llength $dyn] > 0} {
        ev "Ports classified as access by operational mode only (administrative mode is dynamic)" $dyn
    }
}

#------------------------------------------------------------------------------
# DHCP-05 : Option 82
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp05 {} {
    variable SN
    set globalOn [expr {[string length [g_find {^ip dhcp snooping$}]] > 0}]
    set off    [g_find {^no ip dhcp snooping information option$}]
    set on     [g_find {^ip dhcp snooping information option$}]
    set allowU [g_find {^ip dhcp snooping information option allow-untrusted$}]

    if {[string length $off] > 0} {
        add WARNING "Option 82 insertion is explicitly disabled."
        ev "running-config: $off"
    } elseif {!$globalOn} {
        add N/A "DHCP Snooping is not enabled globally; Option 82 not evaluated (see DHCP-02)."
    } else {
        if {$SN(opt82) == "enabled"} {
            if {[string length $on] > 0} {set b "explicitly configured"} else {set b "default behavior, not explicit in running-config"}
            add PASS "Option 82 insertion is enabled ($b)."
        } elseif {$SN(opt82) == "disabled"} {
            add WARNING "Option 82 insertion is reported disabled by \"show ip dhcp snooping\" (no explicit disable command in running-config)."
        } elseif {[string length $on] > 0} {
            add PASS "Option 82 insertion is explicitly configured (effective state not reported by show command)."
        } else {
            add ERROR "Option 82 effective state could not be determined (no explicit command and no state in \"show ip dhcp snooping\")."
        }
    }
    if {[string length $allowU] > 0 || ($globalOn && $SN(opt82_untrusted) == "allowed")} {
        add WARNING "Option 82 packets are accepted from untrusted ports (allow-untrusted)."
    }
}

#------------------------------------------------------------------------------
# DHCP-06 : DHCP snooping binding database
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp06 {} {
    variable RAW
    set url ""
    foreach l [g_all {^ip dhcp snooping database \S+$}] {
        if {[regexp {^ip dhcp snooping database (\S+)$} $l _m u]} {
            set url $u
            break
        }
    }
    if {[string length $url] == 0} {
        add FAIL "DHCP Snooping binding database is not configured (\"ip dhcp snooping database <url>\" not found)."
        return
    }
    ev "running-config: ip dhcp snooping database $url"
    if {!$RAW(db,ok)} {
        add PASS "Database is configured; accessibility could not be verified (\"show ip dhcp snooping database\" unavailable)."
        return
    }
    set t $RAW(db,text)
    foreach {key rx} {
        st {Successful Transfers\s*:\s*([0-9]+)}
        ft {Failed Transfers\s*:\s*([0-9]+)}
        sr {Successful Reads\s*:\s*([0-9]+)}
        fr {Failed Reads\s*:\s*([0-9]+)}
        sw {Successful Writes\s*:\s*([0-9]+)}
        fw {Failed Writes\s*:\s*([0-9]+)}
    } {
        if {[regexp -nocase $rx $t _m v]} {scan $v %d v; set n($key) $v} else {set n($key) ""}
    }
    set parsed 0
    foreach k {st ft sr fr sw fw} {if {[string length $n($k)] > 0} {set parsed 1}}
    foreach k {st ft sr fr sw fw} {if {[string length $n($k)] == 0} {set n($k) 0}}
    set reason ""
    regexp -nocase {Last Failed Reason\s*:\s*([^\n]+)} $t _m reason
    set reason [string trim $reason]
    if {[regexp -nocase {Agent URL\s*:\s*(\S+)} $t _m aurl]} {ev "show ip dhcp snooping database: Agent URL $aurl"}

    if {!$parsed} {
        add PASS "Database is configured; agent statistics could not be parsed, accessibility not confirmed."
        return
    }
    ev "Agent counters - Transfers: ok=$n(st) failed=$n(ft) | Reads: ok=$n(sr) failed=$n(fr) | Writes: ok=$n(sw) failed=$n(fw)"
    if {$n(fw) > 0 || $n(ft) > 0} {
        add WARNING "Database is configured but the agent reports failed writes/transfers (writes failed: $n(fw), transfers failed: $n(ft)); binding persistence is not reliable. Last failure reason: $reason"
    } elseif {$n(sw) > 0} {
        add PASS "Database is configured and writes succeed (successful writes: $n(sw), no failed writes/transfers)."
    } else {
        add PASS "Database is configured; no successful write recorded yet, so accessibility is not yet confirmed."
    }
    if {$n(fr) > 0} {
        ev "Failed reads: $n(fr) (can be benign if no database file existed at startup; bindings may not have been restored after reload)."
    }
}

#------------------------------------------------------------------------------
# DHCP-07 : BOOTP server
#------------------------------------------------------------------------------
proc ::dv::ctl_dhcp07 {} {
    set off [g_find {^no ip bootp server$}]
    set on  [g_find {^ip bootp server$}]
    if {[string length $off] > 0} {
        add PASS "BOOTP server is disabled (explicit configuration)."
        ev "running-config: $off"
    } elseif {[string length $on] > 0} {
        add FAIL "BOOTP server is enabled (explicit configuration)."
        ev "running-config: $on"
    } elseif {[get_all]} {
        if {[all_has {^no ip bootp server\s*$}]} {
            add PASS "BOOTP server is disabled (platform default; not explicit in running-config)."
            ev "show running-config all: no ip bootp server"
        } elseif {[all_has {^ip bootp server\s*$}]} {
            add FAIL "BOOTP server is enabled by platform default (not explicitly disabled)."
            ev "show running-config all: ip bootp server"
        } else {
            add ERROR "BOOTP server state could not be determined (no explicit command and not shown by \"show running-config all\")."
        }
    } else {
        add ERROR "BOOTP server state could not be determined (no explicit command; \"show running-config all\" unavailable)."
    }
}

#------------------------------------------------------------------------------
# Runner / reporting
#------------------------------------------------------------------------------
proc ::dv::banner {} {
    variable HOSTNAME
    variable TITLE
    variable LINKEDIN
    puts [clr DIM [rep "=" 44]]
    puts "  [clr TITLE $TITLE]"
    puts "  [clr LINK $LINKEDIN]"
    puts [clr DIM [rep "=" 44]]
    puts ""
    puts "Platform : Cisco IOS"
    puts "Module   : DHCP Hardening"
    puts "Hostname : $HOSTNAME"
    puts "Mode     : READ-ONLY (show commands only)"
    puts ""
}

proc ::dv::report_control {id title status findings} {
    puts "[clr BOLD "\[$id\]"] [clr BOLD $title]"
    puts "Status: [clr $status $status]"
    foreach f $findings {
        set k [lindex $f 0]
        set t [lindex $f 1]
        set items [lindex $f 2]
        if {$k == "EVIDENCE"} {
            puts "  [clr DIM Evidence:] $t"
        } else {
            puts "  [clr $k "\[$k\]"] $t"
        }
        foreach it $items {puts "    - $it"}
    }
    puts ""
}

proc ::dv::run_all {} {
    variable CONTROLS
    variable FINDINGS
    variable COUNT
    variable RUNOK
    variable RUNERR
    foreach c $CONTROLS {
        set id    [lindex $c 0]
        set title [lindex $c 1]
        set p     [lindex $c 2]
        set FINDINGS {}
        if {!$RUNOK} {
            add ERROR "Cannot read running-config ($RUNERR); control cannot be evaluated."
        } elseif {[catch {$p} err]} {
            add ERROR "Internal error while evaluating this control: $err"
        }
        set worst ""
        set wr -1
        foreach f $FINDINGS {
            set s [lindex $f 0]
            if {$s == "EVIDENCE"} continue
            set r [rank $s]
            if {$r > $wr} {
                set wr $r
                set worst $s
            }
        }
        if {[string length $worst] == 0} {
            set worst ERROR
            add ERROR "Control produced no result."
        }
        incr COUNT($worst)
        report_control $id $title $worst $FINDINGS
    }
}

proc ::dv::summary {} {
    variable COUNT
    puts [clr DIM [rep "=" 44]]
    puts [clr BOLD "SUMMARY"]
    puts [clr DIM [rep "=" 44]]
    puts "[clr PASS "PASS    "]: $COUNT(PASS)"
    puts "[clr FAIL "FAIL    "]: $COUNT(FAIL)"
    puts "[clr WARNING "WARNING "]: $COUNT(WARNING)"
    puts "[clr HINT "HINT    "]: $COUNT(HINT)"
    puts "[clr N/A "N/A     "]: $COUNT(N/A)"
    puts "[clr ERROR "ERROR   "]: $COUNT(ERROR)"
    puts ""
    if {$COUNT(FAIL) > 0} {
        set o [clr FAIL "NON-COMPLIANT"]
    } elseif {$COUNT(ERROR) > 0} {
        set o [clr ERROR "INCOMPLETE (verification errors)"]
    } elseif {$COUNT(WARNING) > 0} {
        set o [clr WARNING "COMPLIANT WITH WARNINGS"]
    } else {
        set o [clr PASS "COMPLIANT"]
    }
    puts "Overall Status: $o"
    puts [clr DIM [rep "=" 44]]
}

proc ::dv::main {} {
    puts "Collecting evidence (read-only show commands)..."
    collect
    banner
    run_all
    summary
}

#------------------------------------------------------------------------------
# Control registry  (add new modules/controls here)
#------------------------------------------------------------------------------
::dv::register DHCP-01 "DHCP Service"          ::dv::ctl_dhcp01
::dv::register DHCP-02 "DHCP Snooping"         ::dv::ctl_dhcp02
::dv::register DHCP-03 "Trusted Interfaces"    ::dv::ctl_dhcp03
::dv::register DHCP-04 "DHCP Rate Limiting"    ::dv::ctl_dhcp04
::dv::register DHCP-05 "DHCP Option 82"        ::dv::ctl_dhcp05
::dv::register DHCP-06 "DHCP Binding Database" ::dv::ctl_dhcp06
::dv::register DHCP-07 "BOOTP Server"          ::dv::ctl_dhcp07

if {[catch {::dv::main} dv_err]} {
    puts "FATAL: verification aborted: $dv_err"
}
