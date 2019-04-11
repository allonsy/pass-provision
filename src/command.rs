use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::process::Command;

pub fn oneshot_command(command: &str, args: &[&str]) -> Result<()> {
    let cmd = Command::new(command).args(args).output();

    if cmd.is_err() {
        return Err(cmd.unwrap_err());
    }

    let cmd_output = cmd.unwrap();
    if !cmd_output.status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "Command: {} exited with status: {}",
                command, cmd_output.status
            ),
        ));
    }

    Ok(())
}
