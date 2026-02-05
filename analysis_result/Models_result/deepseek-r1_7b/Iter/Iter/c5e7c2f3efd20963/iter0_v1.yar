rule Bypass_StackOverflow
{
    meta:
        description = "Evasion bypass via stack overflow."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 EB 8B EC EB FF 75 08 DD EB 08 FF 15 5C C2 4C 00 CA DD 00 4C C2 5C FF D2 FF D2 EE }
        
        $pattern1 = { 56 8B 35 5C 04 51 00 EE EA FF 35 10 93 52 00 DD 00 52 93 10 FF 15 9C C2 4C 00 CA DD 00 4C C2 9C }
        
        $pattern2 = { 8B 4D 08 EA DD ED 4C 8B E5 FF D2 EE }

    condition:
        any_of_them
}