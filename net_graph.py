import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib import style



class NetworkSpeedGraph(FigureCanvas):
    def __init__(self, parent=None):
        #initiliazes the graps
        self.speed_data = {"Download": [], "Upload": [], "Time": []}

        style.use("dark_background")

        self.fig, self.ax = plt.subplots()
        self.ax.set_title("Network Speed Trends", fontsize=14, color="white")
        self.ax.set_xlabel("Time (Tests)", fontsize=12, color="white")
        self.ax.set_ylabel("Speed (Mbps)", fontsize=12, color="white")

        self.line_download, = self.ax.plot([], [], label="Download Speed (Mbps)", color="cyan", linewidth=2)
        self.line_upload, = self.ax.plot([], [], label="Upload Speed (Mbps)", color="magenta", linewidth=2)
        self.ax.legend(facecolor="black", edgecolor="white")

        #Initialize Matplotlib canvas
        super().__init__(self.fig)

        self.ani = animation.FuncAnimation(self.fig, self.animate_graph, interval=1000)

    def update_graph(self, download, upload):
        #in charge of updating the graph when new results come in
        self.speed_data["Time"].append(len(self.speed_data["Time"]) + 1)
        self.speed_data["Download"].append(download)
        self.speed_data["Upload"].append(upload)

    def animate_graph(self, frame):
        self.line_download.set_data(self.speed_data["Time"], self.speed_data["Download"])
        self.line_upload.set_data(self.speed_data["Time"], self.speed_data["Upload"])

        self.ax.relim()
        self.ax.autoscale_view()
