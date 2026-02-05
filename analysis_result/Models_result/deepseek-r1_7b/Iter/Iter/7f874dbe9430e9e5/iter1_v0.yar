rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - increased skip offset for mov ebp, esp"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 EB 8B EC EB FF 75 08 DD EB 08 FF 15 AC B0 41 00 CA DD 00 41 B0 AC }
        $pattern1 = { 8B 45 ED ED 55 EB 8B EC EB FF 75 08 DD EB 08 }
        $pattern2 = { C3 A0 EA 16 79 FF 75 08 DD EB 08 }

    condition:
        any of them
}