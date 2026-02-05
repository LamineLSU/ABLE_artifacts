rule EvasionCodeDetection
{
    meta:
        description = "Detects potential evasion or termination behavior via function prologue and system call to ExitProcess"
        cape_options = "bp0=$func_prologue+0,action0=skip,bp1=$crt_exit+0,action1=skip,bp2=$exit_process+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $func_prologue = { 55 8B EC FF 75 08 } // Function entry setup
        $crt_exit = { E8 C8 FF FF FF } // Call to CRT exit function
        $exit_process = { FF 15 AC B0 41 00 } // Call to ExitProcess

    condition:
        all of them
}