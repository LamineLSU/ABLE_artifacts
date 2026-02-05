rule SandboxExitDetection
{
    meta:
        description = "Detects sandbox exit attempts using ExitProcess or CRT exit functions."
        cape_options = "bp0=$exit1+0,action0=skip,bp1=$exit2+0,action1=skip,bp2=$stack_setup+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"
        platform = "Windows"
    
    strings:
        // Pattern 1: push [ebp+08h] followed by call to ExitProcess
        $exit1 = { FF 75 08 FF 15 ?? ?? ?? ?? }

        // Pattern 2: push [ebp+08h] followed by call to __crtCorExitProcess
        $exit2 = { FF 75 08 E8 ?? ?? ?? ?? }

        // Pattern 3: push ebp, mov ebp, esp, push [ebp+08h]
        $stack_setup = { 55 8B EC FF 75 ?? }

    condition:
        any of ($exit1, $exit2, $stack_setup)
}