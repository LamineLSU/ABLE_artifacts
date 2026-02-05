rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x000C617A+0,action0=skip,bp1=0x000C61C6+0,action1=skip,bp2=0x000C61F0+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? 53 }

    condition:
        any of them
}