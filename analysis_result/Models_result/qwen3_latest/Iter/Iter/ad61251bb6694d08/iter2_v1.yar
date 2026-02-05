rule ControlFlowPatterns
{
    meta:
        author = "Security Researcher"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        description = "Detects control flow patterns in suspicious code"
    strings:
        $a = { 85 C0 74 12 E8 ?? ?? ?? ?? }
        $b = { 85 C0 0F 84 ?? ?? ?? ?? 8B 4D FC }
        $c = { 74 12 E8 ?? ?? ?? ?? }
    condition:
        all of ($a, $b, $c)
}