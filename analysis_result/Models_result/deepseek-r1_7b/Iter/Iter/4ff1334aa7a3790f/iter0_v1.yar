rule EvasionBypass {
    meta:
        description = "Evasion bypass detection using stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 59 45 8B CE E8 C8 FF FF FF FF ?? }   // Push ebp + value then call FCEC with displacement
        $pattern1 = { 8B FF 55 8B EC F7 5A 6A 5A 8B CE E8 ?? } // Multiple pushes followed by jump to FCEC
        $pattern2 = { 03 4D 8B FF 55 8B EC F7 5A 6A 5A 8B CE E8 C8 FF FF FF FF B1 A2 }   // Comprehensive stack manipulation leading to B1A2

    condition:
        any of them
}