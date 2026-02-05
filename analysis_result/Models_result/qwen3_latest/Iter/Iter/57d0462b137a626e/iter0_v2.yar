rule BypassExitCondition
{
    meta:
        description = "Detects and skips sequences that may trigger an exit condition."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 53 E8 ?? ?? ?? ?? }  // push ebx + call ExitProcess
        $b = { 0F 84 ?? ?? ?? ?? }  // je (conditional jump)
        $c = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax + je

    condition:
        any of ($a, $b, $c)
}