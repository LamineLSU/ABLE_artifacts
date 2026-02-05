rule Bypass_Evasion_Plugins_0 {
    meta:
        description = "Evasion bypass rules targeting specific call addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 5A 8B EC FF FF F7 50 8E 8C 8F FF }
        $pattern1 = { 5A 8B EC FF FF F7 50 8E 8C 8F FF F9 5A 12 }
        $pattern2 = { 5A 8B EC FF FF F7 50 8E 8B 1F FF FC 12 }

    condition:
        any of them
}