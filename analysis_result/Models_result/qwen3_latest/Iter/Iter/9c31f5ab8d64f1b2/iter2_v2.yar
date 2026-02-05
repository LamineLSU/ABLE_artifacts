rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? } // CALL + test eax + je (013B6183)
        $pattern1 = { 50 E8 ?? ?? ?? ?? } // push + call (013B61C5)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax + je (013B61A3)

    condition:
        any of them
}