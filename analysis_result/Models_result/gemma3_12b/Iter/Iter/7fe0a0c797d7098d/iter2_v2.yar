rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0007617A+0,action0=skip,bp1=0x000761C6+0,action1=skip,bp2=0x000761F0+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 74 12 }
        $pattern2 = { 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}