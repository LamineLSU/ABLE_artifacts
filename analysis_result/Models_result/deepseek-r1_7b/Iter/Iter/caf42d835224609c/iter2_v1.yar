rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC } // EAX testing
        $pattern1 = { BA D8 F6 34 02 ?? 5A ?? ?? E8 FB 79 FE FF } // Exit decision check
        $pattern2 = { 8D 85 48 F2 FF FF ?? ?? EA EA EB 00 00 0D BC ?? CA } // Timing and VM check

    condition:
        any of them
}