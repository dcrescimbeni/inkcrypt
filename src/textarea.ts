
import blessed from 'blessed';

export async function textarea({
  message,
  defaultValue = ''
}: {
  message: string,
  defaultValue?: string
}): Promise<string> {
  return new Promise((resolve) => {

    const finalize = (value: string) => {
      screen.destroy()
      resolve(value)
    }

    const submit = () => {

      finalize(textarea.getValue());
    };

    const screen = blessed.screen({ smartCSR: true })
    screen.title = message

    const box = blessed.box({
      top: 'center',
      left: 'center',
      width: '90%',
      height: '90%',
      content: 'Ctrl+S to save • Esc twice to cancel',
      tags: true,
      border: {
        type: 'line'
      },
      style: {
        fg: 'white',
        border: { fg: '#f0f0f0' },
      }
    });
    screen.append(box)

    const textarea = blessed.textarea({
      parent: box,
      top: 2,
      bottom: 2,
      width: '99%',
      height: '70%',
      mouse: true,
      inputOnFocus: true,
    })

    textarea.setValue(defaultValue)
    textarea.focus()

    // Quit on Escape, q, or Control-C.
    screen.key(['escape', 'q', 'C-c'], () => process.exit(0));

    screen.render()

    textarea.key(['C-s'], submit);
    screen.key(['C-s'], submit);
  })

}

export async function textarea2({
  message,
  defaultValue = '',
}: {
  message: string;
  defaultValue?: string;
}): Promise<string> {
  return new Promise((resolve) => {
    const previousTerm = process.env.TERM;
    process.env.TERM = 'xterm';

    const program = blessed.program({
      input: process.stdin,
      output: process.stdout,

    });

    const screen = blessed.screen({
      program,
      smartCSR: true,
      autoPadding: true,
      title: message,
    });

    let settled = false;
    const finalize = (value: string) => {
      if (settled) {
        return;
      }

      settled = true;
      if (previousTerm === undefined) {
        delete process.env.TERM;
      } else {
        process.env.TERM = previousTerm;
      }
      screen.program.showCursor();
      screen.destroy();
      resolve(value);
    };

    screen.key(['C-c'], () => {
      finalize('');
    });

    const container = blessed.box({
      parent: screen,
      top: 'center',
      left: 'center',
      width: '100%-8',
      height: '100%-4',
      border: 'line',
      label: ` ${message} `,
      style: {
        border: { fg: 'cyan' },
      },
    });

    blessed.box({
      parent: container,
      top: 0,
      left: 2,
      width: '100%-4',
      height: 1,
      align: 'center',
      tags: true,
      content: '{grey-fg}Ctrl+S to save • Esc to clear • Ctrl+C to cancel{/}',
      style: {
        fg: 'grey',
      },
    });

    const textarea = blessed.textarea({
      parent: container,
      top: 2,
      left: 1,
      width: '100%-2',
      height: '100%-3',
      keys: true,
      mouse: true,
      inputOnFocus: true,
      scrollbar: {
        ch: 'X',
        style: {
          inverse: true,
        },
      },
    });

    textarea.setValue(defaultValue);
    textarea.focus();
    screen.program.hideCursor();
    screen.render();

    textarea.on('focus', () => {
      container.style.border = container.style.border ?? {};
      container.style.border.fg = 'green';
      screen.render();
    });

    textarea.on('blur', () => {
      container.style.border = container.style.border ?? {};
      container.style.border.fg = 'red';
      screen.render();
    });

    const submit = () => {
      finalize(textarea.getValue());
    };

    textarea.key(['C-s'], submit);
    screen.key(['C-s'], submit);
    textarea.key(['escape'], () => {
      textarea.clearValue();
      screen.render();
    });

    textarea.once('blur', () => {
      textarea.focus();
    });
  });
}
