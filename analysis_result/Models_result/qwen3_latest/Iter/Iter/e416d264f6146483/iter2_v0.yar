rule SampleRule
{
    meta:
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 B8 0B 00 00 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 53 E8 ?? ?? ?? ?? }

    condition:
        all of them
}