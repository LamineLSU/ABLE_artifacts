rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting various points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8A 5B FF 75 08 FF 75 08 ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 8B 4D FC 00 74 01 64 A1 30 00 00 00 00 00 00 00 25 41 00 }
        $pattern2 = { 8B C8 FF FF FF FF FF FF FF FF 9C 75 ?? ?? FF 75 08 ?? FF 4E 3D FF ?? FF 65 4F ?? FF FC 18 01 80 }
}

    condition:
        any of them
}