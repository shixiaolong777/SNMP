namespace SnmpDemo
{
    partial class frmSnmp
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.muStorage = new System.Windows.Forms.ToolStripMenuItem();
            this.muRam = new System.Windows.Forms.ToolStripMenuItem();
            this.muCpu = new System.Windows.Forms.ToolStripMenuItem();
            this.muInterfaces = new System.Windows.Forms.ToolStripMenuItem();
            this.mainMenu = new System.Windows.Forms.MenuStrip();
            this.muProcess = new System.Windows.Forms.ToolStripMenuItem();
            this.muTcp = new System.Windows.Forms.ToolStripMenuItem();
            this.muUdp = new System.Windows.Forms.ToolStripMenuItem();
            this.resultBox = new System.Windows.Forms.TextBox();
            this.muSWInstalled = new System.Windows.Forms.ToolStripMenuItem();
            this.mainMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // muStorage
            // 
            this.muStorage.Name = "muStorage";
            this.muStorage.Size = new System.Drawing.Size(66, 21);
            this.muStorage.Text = "Storage";
            this.muStorage.Click += new System.EventHandler(this.muFixedDisk_Click);
            // 
            // muRam
            // 
            this.muRam.Name = "muRam";
            this.muRam.Size = new System.Drawing.Size(48, 21);
            this.muRam.Text = "RAM";
            this.muRam.Click += new System.EventHandler(this.muRam_Click);
            // 
            // muCpu
            // 
            this.muCpu.Name = "muCpu";
            this.muCpu.Size = new System.Drawing.Size(44, 21);
            this.muCpu.Text = "CPU";
            this.muCpu.Click += new System.EventHandler(this.muCpu_Click);
            // 
            // muInterfaces
            // 
            this.muInterfaces.Name = "muInterfaces";
            this.muInterfaces.Size = new System.Drawing.Size(77, 21);
            this.muInterfaces.Text = "Interfaces";
            this.muInterfaces.Click += new System.EventHandler(this.muInterfaces_Click);
            // 
            // mainMenu
            // 
            this.mainMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.muStorage,
            this.muRam,
            this.muCpu,
            this.muProcess,
            this.muInterfaces,
            this.muTcp,
            this.muUdp,
            this.muSWInstalled});
            this.mainMenu.Location = new System.Drawing.Point(0, 0);
            this.mainMenu.Name = "mainMenu";
            this.mainMenu.Size = new System.Drawing.Size(809, 25);
            this.mainMenu.TabIndex = 0;
            this.mainMenu.Text = "menuStrip1";
            // 
            // muProcess
            // 
            this.muProcess.Name = "muProcess";
            this.muProcess.Size = new System.Drawing.Size(65, 21);
            this.muProcess.Text = "Process";
            this.muProcess.Click += new System.EventHandler(this.muProcess_Click);
            // 
            // muTcp
            // 
            this.muTcp.Name = "muTcp";
            this.muTcp.Size = new System.Drawing.Size(42, 21);
            this.muTcp.Text = "TCP";
            this.muTcp.Click += new System.EventHandler(this.muTcp_Click);
            // 
            // muUdp
            // 
            this.muUdp.Name = "muUdp";
            this.muUdp.Size = new System.Drawing.Size(45, 21);
            this.muUdp.Text = "UDP";
            this.muUdp.Click += new System.EventHandler(this.muUdp_Click);
            // 
            // resultBox
            // 
            this.resultBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.resultBox.Font = new System.Drawing.Font("Calibri", 11.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.resultBox.Location = new System.Drawing.Point(0, 25);
            this.resultBox.Multiline = true;
            this.resultBox.Name = "resultBox";
            this.resultBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.resultBox.Size = new System.Drawing.Size(809, 527);
            this.resultBox.TabIndex = 1;
            // 
            // muSWInstalled
            // 
            this.muSWInstalled.Name = "muSWInstalled";
            this.muSWInstalled.Size = new System.Drawing.Size(124, 21);
            this.muSWInstalled.Text = "Installed Software";
            this.muSWInstalled.Click += new System.EventHandler(this.muSWInstalled_Click);
            // 
            // frmSnmp
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(809, 552);
            this.Controls.Add(this.resultBox);
            this.Controls.Add(this.mainMenu);
            this.Font = new System.Drawing.Font("Calibri", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.KeyPreview = true;
            this.MainMenuStrip = this.mainMenu;
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "frmSnmp";
            this.Text = "SNMP Demo";
            this.mainMenu.ResumeLayout(false);
            this.mainMenu.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ToolStripMenuItem muStorage;
        private System.Windows.Forms.ToolStripMenuItem muRam;
        private System.Windows.Forms.ToolStripMenuItem muCpu;
        private System.Windows.Forms.ToolStripMenuItem muInterfaces;
        private System.Windows.Forms.MenuStrip mainMenu;
        private System.Windows.Forms.TextBox resultBox;
        private System.Windows.Forms.ToolStripMenuItem muTcp;
        private System.Windows.Forms.ToolStripMenuItem muUdp;
        private System.Windows.Forms.ToolStripMenuItem muProcess;
        private System.Windows.Forms.ToolStripMenuItem muSWInstalled;

    }
}

