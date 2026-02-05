rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0040E7F6+0,action0=skip,bp1=0x0040E7F3+0,action1=skip,bp2=0x0040E7FF+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 }

    condition:
        any of them
}