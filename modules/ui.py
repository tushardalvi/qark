from threading import Lock
from progressbar import ProgressBar, Percentage, Bar
from modules import common

pbar_file_permission_done = False
lock = Lock()
height = common.term.height

writer1 = common.Writer((0, height-8))
pbar1 = ProgressBar(widgets=['X.509 Validation ', Percentage(), Bar()], maxval=100, fd=writer1).start()
writer2 = common.Writer((0, height-6))
pbar2 = ProgressBar(widgets=['Pending Intents ', Percentage(), Bar()], maxval=100, fd=writer2).start()
writer3 = common.Writer((0, height-4))
pbar3 = ProgressBar(widgets=['File Permissions (check 1) ', Percentage(), Bar()], maxval=100, fd=writer3).start()
writer4 = common.Writer((0, height-2))
pbar4 = ProgressBar(widgets=['File Permissions (check 2) ', Percentage(), Bar()], maxval=100, fd=writer4).start()
writer5 = common.Writer((0, height-10))
pbar5 = ProgressBar(widgets=['Webview checks ', Percentage(), Bar()], maxval=100, fd=writer5).start()
writer6 = common.Writer((0, height-12))
pbar6 = ProgressBar(widgets=['Broadcast issues ', Percentage(), Bar()], maxval=100, fd=writer6).start()
writer7 = common.Writer((0, height-14))
pbar7 = ProgressBar(widgets=['Crypto issues ', Percentage(), Bar()], maxval=100, fd=writer7).start()


def progress_bar_update(count1=None,count2=None,count3=None,count4=None,count5=None,count6=None):
	lock.acquire()
	global pbar_file_permission_done
	if count1 is not None:
		if count1<=100:
			pbar1.update(count1)
	if count2 is not None:
		if count2<=100:
			pbar2.update(count2)
	if count3 is not None:
		if not pbar_file_permission_done:
			if count3<100:
				pbar3.update(count3)
			else:
				pbar3.update(count3)
				pbar_file_permission_done = True
		else:
			pbar4.update(count3)
	if count4 is not None:
		if count4<=100:
			pbar5.update(count4)
	if count5 is not None:
		if count5<=100:
			pbar6.update(count5)
	if count6 is not None:
		if count6<=100:
			pbar7.update(count6)
	lock.release()


