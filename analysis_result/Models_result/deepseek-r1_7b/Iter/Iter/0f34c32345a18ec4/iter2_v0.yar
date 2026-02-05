rule bypass_sample_evolved
{
    meta:
        description = "Bypass Sample Evolved: Exit Decision Check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 83 C4 14 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 8E 03 E2 ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}