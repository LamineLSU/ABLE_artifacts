rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific eversion check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 84 ?? ?? ?? }
        $pattern1 = { 6A 5B 5A 8B CE 0F 84 ?? ?? }
        $pattern2 = { E8 E3 FA FF FF 5F 5E ?? ?? ?? }

    condition:
        any of them
}