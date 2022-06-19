// Modules to control application life and create native browser window
import { app, BrowserWindow } from 'electron';
import path from 'path';

import api from './client-api';

function createWindow () {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // and load the index.html of the app.
  mainWindow.loadFile('index.html');

  // Open the DevTools.
  // mainWindow.webContents.openDevTools();
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
  api.closeDHT();
  if (process.platform !== 'darwin') app.quit();
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.
(async () => {
  /*await api.restoreSession();
  await api.logout();*/

  if (!await api.restoreSession()) {
    api.register('abcd', 'efg');
    await api.login('abcd', 'efg', true);
  }
  await api.uploadFile('main.ts', './main.ts');
  await api.downloadFile('private/main.ts', './main2.ts');
  console.log(await api.getPath('private'));
  await api.shareFile('abcd', 'main.ts');
  await api.downloadFile('shared/main.ts', 'main3.ts');
  await api.register('abc', 'efg');
  await api.login('abc', 'efg', false);
  await api.uploadFile('main2.ts', './main.ts');
  console.log(await api.getPath('private'));
  await api.shareFile('abcd', 'main2.ts');
  await api.login('abcd', 'efg', false);
  console.log(await api.getPath('shared'));
  await api.downloadFile('shared/main2.ts', 'main4.ts');
})();
