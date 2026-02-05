rule Bypass_Sample
{
    meta:
        description: "Evasion bypass rule - uses common structures to bypass two exits"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 89 EA FF 75 08 }
        $pattern1 = { E8 C8 FF FF FF FF 75 08 }
        $pattern2 = { FF 75 08 FF 75 08 FF 75 08 }

    condition:
        any of them
}