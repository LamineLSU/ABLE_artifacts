rule Bypass_Evasion
{
    meta:
        description = "Anti-debugging bypass patterns targeting exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 5A 74 12 85 C0 E8 25 05 00 00 }
        $pattern1 = { 0F 84 FF 84 FF 84 FF 84 74 12 8D 95 F0 FE FF FF }
        $pattern2 = { E9 B5 FC FF FF 85 C0 74 12 0F 84 FF 84 FF 84 FF 84 }
    condition:
        any of them
}