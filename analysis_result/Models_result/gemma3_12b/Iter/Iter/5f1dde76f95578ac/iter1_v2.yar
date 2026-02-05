rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0101617A+0,action0=skip,bp1=0x01016188+0,action1=skip,bp2=0x010161A3+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 85 C0 0F 84 33 FD }

    condition:
        any of them
}