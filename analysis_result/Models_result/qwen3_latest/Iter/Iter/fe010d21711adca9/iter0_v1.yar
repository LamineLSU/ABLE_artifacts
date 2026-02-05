rule ExitProcessCall
{
    meta:
        description = "Detects a call to ExitProcess through conditional jumps and direct calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 85 C0 74 ?? 6A 5B }  // Conditional jump and stack manipulation
        $b = { 85 C0 0F 84 ?? ?? ?? }  // Conditional jump to ExitProcess
        $c = { E8 ?? ?? ?? }  // Direct call to ExitProcess

    condition:
        any of them
}