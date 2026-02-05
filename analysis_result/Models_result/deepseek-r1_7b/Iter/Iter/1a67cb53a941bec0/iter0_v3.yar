rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting test EAX, conditional jump, and memory access"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 75 08 EA DD EB 08 ?? }
        $pattern1 = { 0F 84 33 FD FF FF E9 B5 FC FF FF CD ?? }
        $pattern2 = { 5A E8 25 05 00 00 CA ?? EA DD EB 04 ?? }
        
    condition:
        any of them
}