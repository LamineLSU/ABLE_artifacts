rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x008661F8,action0=skip"

    strings:
        $pattern0 = { FF 15 2C A1 86 00 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B 85 F0 FE FF FF }

    condition:
        $pattern0 or $pattern1 or $pattern2
}