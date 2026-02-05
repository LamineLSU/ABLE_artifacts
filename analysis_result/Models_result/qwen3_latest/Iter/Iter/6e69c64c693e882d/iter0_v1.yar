rule MaliciousCodePattern
{
    meta:
        description = "Detects malicious code patterns involving specific function calls and memory operations"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? }  // Push [ebp+08] followed by call to ___crtCorExitProcess
        $b = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08] followed by call to ExitProcess
        $c = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // Pop ecx, push [ebp+08], then call to ExitProcess
    
    condition:
        all of them
}