rule ExitBypass
{
    meta:
        description = "Detects exit mechanism in target code"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 } {E8 ?? ?? ?? ??}
        $b = { 59 } {FF7508}
        $c = { FF 15 ?? ?? ?? ?? }
    condition:
        all of ($a, $b, $c)
}