rule ExitCallAndProloguePatterns
{
    meta:
        description = "Detects a binary with exit call instructions and a standard function prologue, possibly indicative of evasion techniques."
        cape_options = "bp0=$call_crt_exit+0,action0=skip,bp1=$call_exit_process+0,action1=skip,bp2=$function_prologue+0,action2=skip,count=0"
        confidence = 60

    strings:
        // Pattern 1: Call to ___crtCorExitProcess (standard CRT exit function)
        $call_crt_exit = { E8 C8 FF FF FF 59 FF 75 08 }

        // Pattern 2: Call to ExitProcess (Windows API exit function)
        $call_exit_process = { FF 15 AC B0 41 00 }

        // Pattern 3: Standard function prologue (push ebp, mov ebp, esp, push [ebp+08h])
        $function_prologue = { 55 8B EC FF 75 08 }

    condition:
        all of (
            $call_crt_exit,
            $call_exit_process,
            $function_prologue
        )
}