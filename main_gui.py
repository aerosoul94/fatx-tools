try:
    import Tkinter as tk
    import ttk
    from tkFileDialog import askopenfilename, askdirectory
    import tkMessageBox
except ImportError:
    import tkinter as tk
    from tkinter import ttk
    from tkinter.filedialog import askopenfilename, askdirectory
    import tkinter.messagebox

from fatx_drive import FatXDrive, x_signatures, x360_signatures
from fatx_analyzer import FatXAnalyzer
import os
import sys
import threading
import time
import logging
import argparse

LOG = logging.getLogger("FATX")


class DrivePanel(ttk.Frame):
    def __init__(self, master):
        ttk.Frame.__init__(self, master)
        self.master = master

        self.drive_nodes = {}       # TreeView nodes that have drives
        self.partition_nodes = {}   # TreeView nodes that have partitions

        self.progress_bar = ttk.Progressbar(self, orient='horizontal',
                                            mode='determinate')
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.progress_label_text = tk.StringVar()
        self.progress_label = ttk.Label(self, textvariable=self.progress_label_text)
        self.progress_label.pack(side=tk.BOTTOM, fill=tk.X)

        self.thread = None
        self.analyzer = None
        self.timer0 = None
        self.timer1 = None

        self.pack()
        tree_columns = ('filesize', 'attr', 'cdate', 'mdate', 'adate')
        self.tree = ttk.Treeview(self, columns=tree_columns)
        self.tree.heading('#0', text='Drive Contents')
        self.tree.column('#0', minwidth=100)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.tree.bind("<ButtonRelease-3>", self.open_context_menu)
        # self.tree.heading('cluster', text='Cluster')
        self.tree.heading('filesize', text='File Size')
        self.tree.heading('attr', text='Attributes')
        self.tree.heading('cdate', text='Date Created')
        self.tree.heading('mdate', text='Date Modified')
        self.tree.heading('adate', text='Date Accessed')

        scroll_y = tk.Scrollbar(self.tree, orient=tk.VERTICAL)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.tree.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label='Recover File System..',
                                      command=self.recover_partition)
        self.context_menu.add_command(label='Perform Orphan Analysis',
                                      command=self.run_orphan_scanner)
        self.context_menu.add_command(label='Perform Signature Analysis',
                                      command=self.run_signature_scanner)
        self.context_menu.add_separator()
        self.context_menu.add_command(label='Expand Partition',
                                      command=self.expand_all)
        self.context_menu.add_command(label='Collapse Partition',
                                      command=self.collapse_all)

    def expand_all(self):
        def expand_node(node):
            for child in self.tree.get_children(node):
                self.tree.item(child, open=True)
                expand_node(child)

        partition_node = self.tree.selection()[0]
        self.tree.item(partition_node, open=True)
        expand_node(partition_node)

    def collapse_all(self):
        def collapse_node(node):
            for child in self.tree.get_children(node):
                self.tree.item(child, open=False)
                collapse_node(child)

        partition_node = self.tree.selection()[0]
        self.tree.item(partition_node, open=False)
        collapse_node(partition_node)

    def recover_progress(self):
        file_name = self.thread.current_file[1]
        label_text = 'Recovering: {}'.format(file_name)
        self.progress_label_text.set(label_text)
        self.progress_bar['value'] = self.thread.current_file[0]
        if self.thread.is_alive():
            self.after(100, self.recover_progress)
        else:
            self.progress_label_text.set('')
            self.progress_bar['value'] = 0
            self.timer1 = time.time()
            print('Dump completed in {} seconds'.format(self.timer1 - self.timer0))
            self.master.bell()

    class RecoverPartition(threading.Thread):
        def __init__(self, partition, directory):
            threading.Thread.__init__(self)
            self.partition = partition
            self.directory = directory
            self.current_file = (0, '')

        def run(self):
            for x, dirent in enumerate(self.partition.get_root()):
                self.current_file = (x, dirent.file_name)
                dirent.recover(self.directory)

    def recover_partition(self):
        if self.thread is not None and self.thread.is_alive():
            tkMessageBox.showerror("Error", "Please wait for analysis to finish.")
            return

        # TODO: selection() returns all selected. Support this.
        partition_node = self.tree.selection()[0]
        partition = self.partition_nodes[partition_node]
        directory = askdirectory()
        if directory == '':
            return

        self.thread = self.RecoverPartition(partition, directory)
        self.progress_bar['maximum'] = len(partition.get_root())
        self.timer0 = time.time()
        self.thread.start()
        self.recover_progress()

    def orphan_scanner_progress(self):
        cluster = self.analyzer.current_block
        label_text = "Cluster {}/{}".format(cluster, self.progress_bar['maximum'])
        self.progress_label_text.set(label_text)
        self.progress_bar['value'] = cluster
        if self.thread.is_alive():
            self.after(100, self.orphan_scanner_progress)
        else:
            # self.tree.configure(state='normal')
            self.progress_label_text.set('')
            self.progress_bar['value'] = 0
            self.timer1 = time.time()
            print('analysis completed in {} seconds.'.format(self.timer1 - self.timer0))
            self.master.bell()
            panel = RecoverPanel(self.master, 0)
            self.master.add(panel, text='Analysis results')
            orphans = self.analyzer.get_roots()
            panel.add_orphans(orphans)

    class OrphanScanner(threading.Thread):
        def __init__(self, analyzer):
            threading.Thread.__init__(self)
            self.analyzer = analyzer

        def run(self):
            self.analyzer.perform_orphan_analysis()
            self.analyzer.save_roots('data')

    def run_orphan_scanner(self):
        if self.thread is not None and self.thread.is_alive():
            tkMessageBox.showerror("Error", "Please wait for analysis to finish.")
            return

        partition_node = self.tree.selection()[0]
        partition = self.partition_nodes[partition_node]
        self.analyzer = FatXAnalyzer(partition)

        self.thread = self.OrphanScanner(self.analyzer)
        self.progress_bar['maximum'] = self.analyzer.volume.max_clusters
        # self.tree.state(('disabled',))
        self.timer0 = time.time()
        self.thread.start()
        self.orphan_scanner_progress()
        pass

    def signature_scanner_progress(self):
        cluster = self.analyzer.current_block
        label_text = "Block {}/{}".format(cluster, self.progress_bar['maximum'])
        self.progress_label_text.set(label_text)
        self.progress_bar['value'] = cluster
        if self.thread.is_alive():
            self.after(100, self.signature_scanner_progress)
        else:
            # self.tree.configure(state='normal')
            self.progress_label_text.set('')
            self.progress_bar['value'] = 0
            self.timer1 = time.time()
            print('analysis completed in {} seconds.'.format(self.timer1 - self.timer0))
            self.master.bell()
            panel = RecoverPanel(self.master, 1)
            self.master.add(panel, text='Analysis results')
            orphans = self.analyzer.get_valid_sigs()
            panel.add_entries(orphans)

    class SignatureScanner(threading.Thread):
        def __init__(self, analyzer, signatures, interval=0x200, length=0):
            threading.Thread.__init__(self)
            self.analyzer = analyzer
            self.signatures = signatures
            self.interval = interval
            self.length = length

        def run(self):
            self.analyzer.perform_signature_analysis(signatures=self.signatures,
                                                     interval=self.interval,
                                                     length=self.length)

    def run_signature_scanner(self):
        if self.thread is not None and self.thread.is_alive():
            tkMessageBox.showerror("Error", "Please wait for analysis to finish.")
            return

        partition_node = self.tree.selection()[0]
        partition = self.partition_nodes[partition_node]
        self.analyzer = FatXAnalyzer(partition)
        # TODO: this is nasty, don't do this
        signatures = x360_signatures if self.analyzer.volume.endian_fmt == '>' else x_signatures

        self.thread = self.SignatureScanner(self.analyzer, signatures=signatures)
        self.progress_bar['maximum'] = self.analyzer.volume.length / 0x200  # TODO: analyzer.get_interval()
        self.timer0 = time.time()
        self.thread.start()
        self.signature_scanner_progress()
        pass

    def open_context_menu(self, event):
        item = self.tree.identify('row', event.x, event.y)
        self.tree.selection_set(item)
        self.tree.focus(item)
        if item in self.partition_nodes:
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root, 0)
            finally:
                self.context_menu.grab_release()
            return

    def add_drive(self, path):
        # close this file upon termination
        # or when drive is closed.
        # file handle is needed for performing work.
        infile = open(path, 'rb')
        drive = FatXDrive(infile)

        # insert entry for this drive
        file_name = os.path.basename(path)
        drive_root = self.tree.insert('', tk.END, text=file_name)
        for index, partition in enumerate(drive.partitions):
            partition_name = partition.name + \
                ' (Offset={:#x} Length={:#x})'.format(partition.offset, partition.length)
            partition_root = self.tree.insert(drive_root, tk.END, text=partition_name)

            try:
                partition.mount()
                self.populate_directory(partition_root, partition.get_root())
                self.partition_nodes[partition_root] = partition
            except Exception as e:
                print(e)

        self.drive_nodes[drive_root] = drive

    @staticmethod
    def format_attributes(attr):
        attr_str = ''
        if attr & 0x1:
            attr_str += 'RO '
        if attr & 0x2:
            attr_str += 'HDN '
        if attr & 0x4:
            attr_str += 'SYS'
        if attr & 0x10:
            attr_str += 'DIR'
        if attr & 0x20:
            attr_str += 'ARC'
        if attr & 0x40:
            attr_str += 'DEV'
        if attr & 0x80:
            attr_str += 'NML'
        return attr_str

    def populate_directory(self, tree_root, stream):
        for dirent in stream:
            if dirent.is_deleted():
                file_name = '[DELETED] {}'.format(dirent.file_name)
            else:
                file_name = dirent.file_name
            if dirent.is_directory():
                if len(dirent.children) == 256:
                    print('WARN: %s has max files' % dirent.get_full_path())
                dir_root = self.tree.insert(tree_root, tk.END, text=file_name,
                                            values=('', self.format_attributes(dirent.file_attributes),
                                                    str(dirent.creation_time),
                                                    str(dirent.last_write_time),
                                                    str(dirent.last_access_time)))
                self.populate_directory(dir_root, dirent.children)
            else:
                self.tree.insert(tree_root, tk.END, text=file_name,
                                 values=('{} bytes'.format(dirent.file_size),
                                         self.format_attributes(dirent.file_attributes),
                                         str(dirent.creation_time),
                                         str(dirent.last_write_time),
                                         str(dirent.last_access_time)))


class RecoverPanel(ttk.Frame):
    def __init__(self, master, mode):
        ttk.Frame.__init__(self, master)
        self.master = master
        self.mode = mode
        self.pack()
        # Add offset
        tree_columns = ('cluster', 'filesize', 'cdate', 'mdate', 'adate')
        self.tree = ttk.Treeview(self, columns=tree_columns)
        self.tree.heading('#0', text='File Name')
        self.tree.heading('cluster', text='Cluster')
        self.tree.heading('filesize', text='File Size')
        self.tree.heading('cdate', text='Date Created')
        self.tree.heading('mdate', text='Date Modified')
        self.tree.heading('adate', text='Date Accessed')
        column_width = 170
        self.tree.column('filesize', minwidth=column_width, width=column_width, stretch=False)
        self.tree.column('cdate', minwidth=column_width, width=column_width, stretch=False)
        self.tree.column('mdate', minwidth=column_width, width=column_width, stretch=False)
        self.tree.column('adate', minwidth=column_width, width=column_width, stretch=False)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.tree.bind("<ButtonRelease-3>", self.open_context_menu)

        scroll_y = tk.Scrollbar(self.tree, orient=tk.VERTICAL)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.tree.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label='Recover this node..', command=self.recover_orphan) # recover file or folder
        self.context_menu.add_command(label='Recover all..', command=self.recover_all)
        # self.context_menu.add_command(label='Save to database', command=self.save_database)
        self.context_menu.add_separator()
        self.context_menu.add_command(label='Expand all', command=self.expand_all)
        self.context_menu.add_command(label='Collapse all', command=self.collapse_all)

        self.orphan_nodes = {}

    def recover_cluster(self, item, path):
        for child_item in self.tree.get_children(item):
            dirent = self.orphan_nodes[child_item]
            dirent.recover(path)

    def recover_all(self):
        directory = askdirectory()
        if directory == '':
            return

        if self.mode == 0:
            for cluster_item in self.tree.get_children():
                # create directory for this cluster
                # cluster_item is same as text
                cluster_path = directory + '/' + cluster_item
                if not os.path.exists(cluster_path):
                    os.mkdir(cluster_path)

                self.recover_cluster(cluster_item, cluster_path)
        elif self.mode == 1:
            for item in self.tree.get_children():
                dirent = self.orphan_nodes[item]
                dirent.recover(directory)
        self.master.bell()

    def recover_orphan(self):
        item = self.tree.selection()[0]
        dirent = self.orphan_nodes[item]
        directory = askdirectory()
        if directory == '':
            return

        if dirent is None:
            # this is a cluster node
            self.recover_cluster(item, directory)
        else:
            # this is a file or directory
            dirent.recover(directory)
        self.master.bell()

    def expand_all(self):
        def expand_node(node):
            for child in self.tree.get_children(node):
                self.tree.item(child, open=True)
                expand_node(child)

        for root in self.tree.get_children():
            expand_node(root)

    def collapse_all(self):
        def collapse_node(node):
            for child in self.tree.get_children(node):
                self.tree.item(child, open=False)
                collapse_node(child)

        for root in self.tree.get_children():
            self.tree.item(root, open=False)

    def open_context_menu(self, event):
        item = self.tree.identify('item', event.x, event.y)
        self.tree.selection_set(item)
        self.tree.focus(item)
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root, 0)
        finally:
            self.context_menu.grab_release()
        # we know which item it is, now grab the file info and dump

    def add_children(self, children, root_node=''):
        for child in children:
            if child.is_directory():
                if len(child.children) == 256:
                    print('WARN: directory %s contains max files' % child.get_full_path())
                orphan_node = self.tree.insert(root_node, tk.END, text=child.file_name,
                                        values=(child.cluster, '',
                                        str(child.creation_time),
                                        str(child.last_write_time),
                                        str(child.last_access_time)))
                self.add_children(child.children, orphan_node)
            else:
                orphan_node = self.tree.insert(root_node, tk.END, text=child.file_name,
                                 values=(child.cluster,
                                        '{} bytes'.format(child.file_size),
                                         str(child.creation_time),
                                         str(child.last_write_time),
                                         str(child.last_access_time)))
            self.orphan_nodes[orphan_node] = child

    def add_orphans(self, roots):
        self.tree.delete(*self.tree.get_children())
        # add RootX for each of same cluster?
        for root in roots:
            cluster_node = 'Cluster' + str(root.cluster)
            if not self.tree.exists(cluster_node):
                cluster_node = self.tree.insert('', tk.END, iid=cluster_node, text=cluster_node)
                self.orphan_nodes[cluster_node] = None
            if root.is_directory():
                root_node = self.tree.insert(cluster_node, tk.END, text=root.file_name,
                                             values=(root.cluster,))
                self.add_children(root.children, root_node)
            else:
                root_node = self.tree.insert(cluster_node, tk.END, text=root.file_name,
                                 values=(root.cluster,
                                         '{} bytes'.format(root.file_size),
                                         str(root.creation_time),
                                         str(root.last_write_time),
                                         str(root.last_access_time)))
            self.orphan_nodes[root_node] = root

    def add_entries(self, sign_entries):
        self.tree.delete(*self.tree.get_children())
        for entry in sign_entries:
            byte_size = '%d bytes' % entry.length
            entry_node = self.tree.insert('', tk.END, text=entry.get_file_name(), values=(byte_size, ''))
            self.orphan_nodes[entry_node] = entry


class MainFrame(ttk.Frame):
    def __init__(self, master):
        ttk.Frame.__init__(self, master, width=1080, height=720)
        self.pack(expand=True, fill=tk.BOTH)
        self.master = master

        # style = ttk.Style()
        # style.theme_use('clam')

        self.menu = tk.Menu(self.master)
        self.master.config(menu=self.menu)
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='File', menu=self.file_menu)
        self.menu.add_cascade(label='Help', menu=self.help_menu)
        self.file_menu.add_command(label="Open..", command=self.open_image)
        self.file_menu.add_command(label="Exit", command=self.master.quit)
        self.help_menu.add_command(label="About..")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.drive_tab = DrivePanel(self.notebook)
        self.notebook.add(self.drive_tab, text='Drives')

    def open_image(self, file_name=''):
        if file_name == '':
            file_name = askopenfilename()
            if file_name == '':
                return

        self.drive_tab.add_drive(file_name)

def main():
    root = tk.Tk()

    frame = MainFrame(root)
    # if len(sys.argv) > 1:
    #     frame.open_image(sys.argv[1])

    root.title('FatX-Recover')
    root.minsize(1200, 720)

    '''
    root.wm_title("FatX-Recover")
    # set background color
    root['bg'] = 'grey'

    s = ttk.Style()

    print s.theme_names()
    s.theme_use('vista')
    # fieldbackground = actual background
    # background = background of nodes
    # foreground = text color
    s.configure('Treeview',
                background='black',
                foreground='white',
                fieldbackground='black',
                selectbackground='green')
    s.configure('Treeview.Heading', background='grey',
                foreground='white',
                relief='flat')
    '''
    root.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GUI for fatx-tools.')
    parser.add_argument("-v", "--verbose", help="Verbose.", action='store_true')
    args = parser.parse_args()

    _stream = logging.StreamHandler(sys.stdout)
    _stream.setLevel(logging.INFO)
    _stream.setFormatter(logging.Formatter('%(levelname).4s: %(message)s'))

    if args.verbose:
        _file = logging.FileHandler("log.txt", "w", "utf-8")
        _file.setLevel(logging.DEBUG)
        _file.setFormatter(
            logging.Formatter('%(module)s::%(funcName)s::%(lineno)d %(levelname).4s %(asctime)s - %(message)s'))
        LOG.setLevel(logging.DEBUG)
        LOG.addHandler(_file)

    LOG.addHandler(_stream)

    main()
