rule Bypass_Evasion
{
    meta:
        description: "Evasion bypass using different return paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF C0 6D 24 ?? 9E 74 00 }
        $pattern1 = { E8 FF 3A ?? 5C 00 C0 FF 3A }
        $pattern2 = { 6A 9D 7B FF 41 FF C8 E8 }

    condition:
        any of them
}