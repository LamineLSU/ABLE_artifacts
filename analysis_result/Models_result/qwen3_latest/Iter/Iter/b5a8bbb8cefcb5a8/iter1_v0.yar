rule Targeted_Evasion_Check
{
    meta:
        description = "Detects evasion check and exit decision sequences from the trace"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 C8 ?? ?? ?? 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $b = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h] followed by ExitProcess call
        $c = { 55 8B EC FF 75 08 }  // Push ebp, mov ebp, esp, push [ebp+08h]
    condition:
        all of them
}