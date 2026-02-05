rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 CE ?? ?? ?? ?? }  // From TRACE //1: E8 followed by CE and four wildcards
        $pattern1 = { E8 C8 FF FF ?? ?? ?? } // From TRACE //2: E8C8FFFF with four wildcards
        $pattern2 = { FF 15 AC B0 41 00 }   // From TRACE //3: Direct instruction sequence

    condition:
        any of them
}