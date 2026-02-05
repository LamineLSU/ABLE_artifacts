rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x00DD617A+0,action0=skip,bp1=0x00DD61A3+0,action1=skip,bp2=0x00DD61E2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B }
        $pattern1 = { 0F 84 33 FD FF FF 8B }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}