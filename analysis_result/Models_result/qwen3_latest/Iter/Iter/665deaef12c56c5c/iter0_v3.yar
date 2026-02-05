rule MaliciousCodePattern
{
    meta:
        description = "Detects potential malicious code patterns involving stack manipulation and function calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp, mov ebp, push dword [ebp+08h], call (CRT exit)
        $b = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }    // Pop ecx, push dword [ebp+08h], call (ExitProcess)
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? }       // Push dword [ebp+08h], call (ExitProcess)
    
    condition:
        all of them
}