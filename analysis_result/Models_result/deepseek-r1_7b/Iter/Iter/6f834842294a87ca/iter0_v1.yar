rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5A ?? 4F ?? FF ?? C8 FF FF FF FE }
        $pattern1 = { FF 75 08 E8 C8 FF FE FF AC B0 41 00 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 59 45 }
    condition:
        any of them
}