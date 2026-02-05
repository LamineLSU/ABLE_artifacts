rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule with refined patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 586D74C3C3F15E419040C0006164A3151 }
        $pattern1 = { D1E5B4F84D6A2501C13A51007040F510A }
        $pattern2 = { 9C78F3C1D140C1C1D5A3D101C00000000 }

    condition:
        any of them
}