rule ConditionalFlowControl
{
    meta:
        description = "Detects conditional flow control patterns involving test, jump, and call instructions."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $b = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $c = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        all of them
}