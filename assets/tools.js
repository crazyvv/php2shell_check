'use strict';

for (const button of document.querySelectorAll('[data-copy-command]')) {
  const command = document.getElementById(button.dataset.copyCommand);
  const status = document.getElementById(button.getAttribute('aria-describedby'));
  button.hidden = false;
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(command.textContent);
      status.textContent = '命令已复制。';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(command);
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = '命令已选中，请使用系统复制快捷键。';
    }
  });
}
