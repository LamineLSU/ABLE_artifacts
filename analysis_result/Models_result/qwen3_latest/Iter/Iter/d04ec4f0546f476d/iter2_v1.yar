rule ConditionalFlow
{
    meta:
        description = "Detects conditional flow leading to TerminateProcess and ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 83 F8 01 74 ?? 64 A1 ?? ?? ?? ?? }
        $b = { A8 01 75 ?? 64 A1 ?? ?? ?? ?? }
        $c = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 0F 84 ?? ?? ?? ?? }
    
    condition:
        all of them
}