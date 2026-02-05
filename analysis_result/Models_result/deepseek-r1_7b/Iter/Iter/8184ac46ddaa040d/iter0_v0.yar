rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection rules targeting specific execution paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 C7 61 A3 E8 00 C7 61 A5 25 00 C7 61 A7 00 00 C7 61 A9 C0 00 C7 61 AC 5A 00 C7 61 AE 00 C7 61 AF EA 00 C7 61 B1 E8 00 C7 61 B3 45 00 C7 61 B5 ?? 00 C7 61 B7 00 C7 61 B9 EB 00 C7 61 BC ?? 00 C7 61 BD 00 C7 61 BE ?? 00 C7 61 BF 00 C7 61 C0 DD 00 C7 61 C2 00 C7 61 C4 ?? }
        $pattern1 = { 00 DC A9 A1 8B 00 DC A9 A3 FF 00 DC A9 A5 75 00 DC A9 A7 08 00 DC A9 AA E8 00 DC A9 AB C0 00 DC A9 AC F4 00 DC A9 AD 26 00 DC A9 AE 00 00 DC A9 AF 00 00 DC A9 B1 FF 00 DC A9 B3 75 00 DC A9 B5 08 00 DC A9 B7 00 DC A9 BA DD 00 DC A9 BC 00 DC A9 BD ?? }
        $pattern2 = { 01 32 61 DB E8 01 32 61 DC 0B 01 32 61 DD FF 01 32 61 DE 0C 01 32 61 DF 45 01 32 61 E1 ?? 01 32 61 E3 01 32 61 E5 EB 01 32 61 E7 01 32 61 EA ?? 01 32 61 EB E8 01 32 61 EC F4 01 32 61 ED 5C 01 32 61 EE ?? 01 32 61 EF 01 32 61 F0 DD 01 32 61 F2 }
    condition:
        (any of $pattern0, $pattern1, $pattern2 matches)
}