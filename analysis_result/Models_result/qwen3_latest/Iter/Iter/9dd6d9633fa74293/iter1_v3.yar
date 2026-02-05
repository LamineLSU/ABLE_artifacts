rule CodeFlowPatterns
{
    meta:
        description = "Detects specific code flow patterns in memory or binary data"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = FF7508 E8 ?? ?? ?? ??  // Push ebp+0x08, Call (first function)
        $pattern1 = FF7508 FF15 ?? ?? ?? ??  // Push ebp+0x08, Call (second function)
        $pattern2 = 8BEC FF7508  // Mov ebp, esp; Push ebp+0x08

    condition:
        all of them
}