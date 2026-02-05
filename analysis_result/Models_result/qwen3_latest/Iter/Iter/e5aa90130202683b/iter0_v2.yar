rule SandboxDetection
{
    meta:
        description = "Potential sandbox detection logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 8B 46 08 E8 ?? ?? ?? ?? F7 D8 }
        $b = { 03 46 0C E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $c = { 8B 5E 58 E8 ?? ?? ?? ?? 53 }

    condition:
        any of ($a, $b, $c)
}