rule Bypass_Sample
{
    meta:
        description = "Evasion bypass sequences targeting function calls and jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 3C 96 5A ?? ?? ?? 8B 4E 07 00 00 00 } // Pushes and call bypass
        $pattern1 = { 00 41 3D 27 5A ?? ?? ?? 8B 4F C5 FF FF FF } // Another call bypass path
        $pattern2 = { 00 41 3D 0C 5A ?? ?? ?? 8B 4E 09 FF FF FF } // Third bypass sequence
}

condition:
    any of them