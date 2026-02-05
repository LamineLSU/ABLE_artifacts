rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 ?? } // Call + test eax + je (evasion check)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }     // Test eax + je (conditional flow)
        $pattern2 = { FF 15 ?? ?? ?? ?? 33 FF 8B 4D FC } // Exit call + xor + mov (exit decision logic)

    condition:
        any of them
}