rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 05 00 00 85 C0 74 12 }  // CALL + TEST EAX + JE (early check)
        $pattern1 = { E8 ?? FA FF FF 85 C0 0F 84 ?? } // CALL + TEST EAX + LJMP (conditional exit)
        $pattern2 = { E8 ?? FA FF FF 85 C0 74 ?? }   // CALL + TEST EAX + JE (secondary check)

    condition:
        any of them
}