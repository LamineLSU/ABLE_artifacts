rule Bypass_Escapealysis
{
    meta:
        description = "Bypass ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 45 00 4B 7A 0F 30 59 ?? 8D 4C ?? 4E ?? FF }
        $pattern1 = { 6A 41 55 ?? 55 8D 45 30 ?? ?? 00 8B CE E8 20 8B 00 ?? }
        $pattern2 = { BE 48 22 47 00 8E 4C 00 6A 01 5A C0 8D 30 9E 30 8D 00 FF }

    condition:
        any of them
}